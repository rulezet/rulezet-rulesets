rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_aSl2g6j_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aSl2g6j_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a592af4ebdb4f4ab288659f8c97a0977095038ea7267bd353246c89ea36dd302"

  strings:
    $s1  = "FeatureQueryLogger::Start() > Query Logger - Static FeatureGate Logging Disabled" fullword wide
    $s2  = "GetMachineDetailsNonWmi - Failed to get OS name from registry" fullword wide
    $s3  = "Utils.cpp > ReadEcsConfigMapFromReg > Invalid value during conversion." fullword wide
    $s4  = "Utils.cpp > GetAppName > Could not get current appinfo." fullword wide
    $s5  = "NetworkCheck::CanExecuteRequest > ShouldExecuteRequest is returning HighCostNetworkError because the network is high cost." fullword wide
    $s6  = "NetworkCheck::CanExecuteRequest > ShouldExecuteRequest is returning NetworkUnavailableError due to lack of network connectivity." wide
    $s7  = "NetworkCheck::CanExecuteRequest > ShouldExecuteRequest is returning NetworkDisallowedError because network use is not permitted." wide
    $s8  = "OrapiUtils.cpp > GetBuildNumber > Could not get build number from registry." fullword wide
    $s9  = "Utils.cpp > ParseRfc1123Time > The time parsing to system time failed." fullword wide
    $s10 = "Utils.cpp > ReadEcsConfigMapFromReg > Unexpected type found in flight list" fullword wide
    $s11 = "Utils.cpp > MigrateEcsConfigData > Failed to write EcsConfigResponseData" fullword wide
    $s12 = "Failed override reads" fullword wide
    $s13 = "Persistent.h > operator T() > Tried reading value from registry but failed." fullword wide
    $s14 = "HttpSupport::GetStatus > Http status was not OK on return from request" fullword wide
    $s15 = "HttpSupport::GetResponseHeaders > Failed to get header data" fullword wide
    $s16 = "HttpSupport::GetResponse > Failed to get response data" fullword wide
    $s17 = "OrapiUtils.cpp > GetBuildNumber > Got registry buffer size of 0." fullword wide
    $s18 = "VersionedRegistry::FReadChunckedData > bad_alloc getting memory for data." fullword wide
    $s19 = "VersionedRegistry::FReadChunckedData > RegistryException getting chunkCount." fullword wide
    $s20 = "Failed to initialize context with user agent." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}