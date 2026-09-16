rule VirusShareTrojanSiggen1537225 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen1537225.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4900ce5700b694d7a212fc4ed2230dddcf93e8a76b30dca268e482e10276ea45"

  strings:
    $x1  = "RtlDosPathNameToNtPathName_U_WithStatuscipher: incorrect tag size given to GCMcrypto/rsa: invalid options for Decrypthttp: putId" ascii
    $x2  = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)tls: ECDSA signing requires a ECDSA " ascii
    $x3  = " > (den<<shift)/2unexpected end of JSON inputunexpected protocol version  cannot be converted to type 45474735088646411895751953" ascii
    $x4  = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETCent" ascii
    $x5  = "UnregisterPowerSettingNotificationVirtualQuery for stack base failedadding nil Certificate to CertPoolcouldn't create a new ciph" ascii
    $x6  = " MB) workers= called from  flushedWork  gcscanvalid  heap_marked= idlethreads= in host name is nil, not  nStackRoots= out of ran" ascii
    $x7  = "unknown network workbuf is emptywww-authenticate initialHeapLive= spinningthreads=%%!%c(big.Int=%s)0123456789ABCDEFX0123456789ab" ascii
    $x8  = "sync: WaitGroup misuse: Add called concurrently with Waittls: Ed25519 public keys are not supported before TLS 1.2tls: peer does" ascii
    $x9  = " to unallocated span%%!%c(*big.Float=%s)37252902984619140625Arabic Standard TimeAzores Standard TimeCertFindChainInStoreCertOpen" ascii
    $x10 = "unixpacketunknown pcuser-agentuser32.dllws2_32.dll  of size   (targetpc= ErrCode=%v a.npages=  b.npages=  gcwaiting= gp.status= " ascii
    $x11 = "tls: ECDSA signature contained zero or negative valuestls: client indicated early data in second ClientHellotls: failed to creat" ascii
    $x12 = "streamSafe was not resetstructure needs cleaningtext/html; charset=utf-8unexpected buffer len=%vunexpected exponent baseunexpect" ascii
    $x13 = " of unexported method previous allocCount=186264514923095703125931322574615478515625AdjustTokenPrivilegesAlaskan Standard TimeAn" ascii
    $x14 = "Pakistan Standard TimeParaguay Standard TimeRtlGetNtVersionNumbersSakhalin Standard TimeTasmania Standard TimeUUID must not be e" ascii
    $x15 = "23283064365386962890625<invalid reflect.Value>Argentina Standard TimeAstrakhan Standard TimeCLIENT_TRAFFIC_SECRET_0CertGetCertif" ascii
    $x16 = "(MISSING)(unknown)+infinity, newval=, oldval=-07:00:00-infinity/api/cdn?244140625: status=; Domain=Accuracy(AuthorityBassa_VahBh" ascii
    $x17 = "Already ReportedConnectNamedPipeContent-EncodingContent-LanguageContent-Length: CreateDirectoryWCreateJobObjectWCreateNamedPipeW" ascii
    $x18 = "RtlNtStatusToDosErrorNoTebSaint Pierre Standard TimeSetFileInformationByHandleSetProcessWorkingSetSizeExSetSecurityDescriptorGro" ascii
    $x19 = "flate: internal error: garbage collection scangcDrain phase incorrecthttp2: handler panickedhttp2: invalid trailershttp: request" ascii
    $x20 = "file descriptor in bad statefindrunnable: netpoll with pgcstopm: negative nmspinninggeneral SOCKS server failurehttp2: Transport" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*)
}