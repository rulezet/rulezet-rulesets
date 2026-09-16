rule Trojan_Autorun_Trojan_GenericKD_34338697 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.34338697.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efd8f71ed5b518b5c8abcd94a7533228953dd5dab430bb683c221abcd26a8f43"

  strings:
    $s1  = "AcquireCredentials failed)None of needed security package was found#Could not query package information Error querying local cer" wide
    $s2  = "Not supportedBCould not load the dll (schannel.dll, security.dll or secur32.dll)-Could not get security initialization routine)C" wide
    $s3  = "Invalid Stream operation!Uncompressing error - invalid crc'Uncompressing error - invalid data size" fullword wide
    $s4  = "The logon attempt failed;The credentials supplied to the package were not recognized4No credentials are available in the securit" wide
    $s5  = "Generic trust failure2A certificate was explicitly revoked by its issuerjThe certification path terminates with the test root wh" wide
    $s6  = "E:\\DComponent\\Clever Internet Suite v9.1.0\\SourceFiles\\common\\clHeaderFieldList.pas" fullword wide
    $s7  = "E:\\DComponent\\Clever Internet Suite v9.1.0\\SourceFiles\\common\\clFtpUtils.pas" fullword wide
    $s8  = "SOCKS error: TTL expired\"SOCKS error: Command not supported'SOCKS error: Address type not supported" fullword wide
    $s9  = "E:\\DComponent\\Clever Internet Suite v9.1.0\\SourceFiles\\common\\clInternetConnection.pas" fullword wide
    $s10 = "E:\\DComponent\\Clever Internet Suite v9.1.0\\SourceFiles\\common\\clCryptHash.pas" fullword wide
    $s11 = "E:\\DComponent\\Clever Internet Suite v9.1.0\\SourceFiles\\common\\clHttp.pas" fullword wide
    $s12 = "E:\\DComponent\\Clever Internet Suite v9.1.0\\SourceFiles\\common\\clHttpRequest.pas" fullword wide
    $s13 = "Failed to obtain size of file#Unable to open key \"%s\\%s\" for read0Unable to open key \"%s\\%s\" and access value \"%s\"#\"%s" wide
    $s14 = "Unsupported firewall type&Old input was not completely processed" fullword wide
    $s15 = "E:\\DComponent\\Clever Internet Suite v9.1.0\\SourceFiles\\common\\clSyncUtils.pas" fullword wide
    $s16 = "E:\\DComponent\\Clever Internet Suite v9.1.0\\SourceFiles\\common\\clSocket.pas" fullword wide
    $s17 = "E:\\DComponent\\Clever Internet Suite v9.1.0\\SourceFiles\\common\\clStreams.pas" fullword wide
    $s18 = "E:\\DComponent\\Clever Internet Suite v9.1.0\\SourceFiles\\common\\clSocks.pas" fullword wide
    $s19 = "E:\\DComponent\\Clever Internet Suite v9.1.0\\SourceFiles\\common\\clTlsSocket.pas" fullword wide
    $s20 = "E:\\DComponent\\Clever Internet Suite v9.1.0\\SourceFiles\\common\\clZLibStreams.pas" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}