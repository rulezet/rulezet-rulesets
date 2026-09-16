rule Virus_Autorun_Win32_Neshta_A_20 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_20.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a51ea394b564772bec07ecd1e683c8ab963ae22e8a6af743f16d9c37a0d2127e"

  strings:
    $s1  = "[ERROR] Fail to ExecuteProcess in CV3LUpWrapper::V3LUpByV3LRun, dwRtnVaue=%d" fullword wide
    $s2  = "[ERROR] Fail to ShellExecute in CV3LUpWrapper::V3LUpByV3LRun, GetLastError=%d" fullword wide
    $s3  = "[INFO] Try to ::ShellExecute open V3LRun szArg=%s, GetInstallPath=%s, SW_SHOWNORMAL in CV3LUpWrapper::UpdateByV3LRun" fullword wide
    $s4  = "[ERROR]GetUseUAC() - RegOpenKeyEx() returned %d" fullword wide
    $s5  = "[ERROR] Fail to RegOpenKeyEx=%d in GetIsUseRtsDupProduct" fullword wide
    $s6  = "[ERROR] Fail to RegOpenKeyEx in CProductBranch::GetProductShortName, lReult=%d, GetLastError=%d" fullword wide
    $s7  = "[INFO] V3LExec.exe executed" fullword wide
    $s8  = "[ERROR] IsVista - GetVersionInfoEx() returned FALSE (error-code:%d)" fullword wide
    $s9  = "[INFO] V3LExec.exe finished" fullword wide
    $s10 = "[ERROR] Fail to V3LAuth.dll Load" fullword wide
    $s11 = "[INFO] ShellExecuteEx, BEGIN" fullword wide
    $s12 = "[INFO] ShellExecuteEx, FINISH" fullword wide
    $s13 = "[ERROR] [CAhnChannelPipeImpl::WaitForConnection] ConnectNamedPipe failed(%d)" fullword wide
    $s14 = "[ERROR] Fail to GetComponentIniPath, dwRtnValue=%d, in GetDriverComponentName" fullword wide
    $s15 = "[ERROR] Fail to GetComponentIniPath, dwRtnValue=%d, in GetRegisterComponentName" fullword wide
    $s16 = "[INFO] Terminate Process Success %s, %d, %d" fullword wide
    $s17 = "[ERROR] GetUseUAC() - dwValue is invalid" fullword wide
    $s18 = "[ERROR] [CAhnChannelPipeImpl::Connect] GetNamedPipeInfo failed(%d)" fullword wide
    $s19 = "[ERROR] [CAhnChannelPipeImpl::Read] The first read operation failed(%d)" fullword wide
    $s20 = "[ERROR] [CAhnChannelPipeImpl::Read] The second read operation failed(%d)" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}