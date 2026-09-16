rule INFO_KCP_MZ_FILE {
  meta:
    version      = "1"
    date         = "1/17/24"
    modified     = "1/17/24"
    status       = "DEVELOPMENT"
    sharing      = "TLP:CLEAR"
    source       = "https://github.com/skywind3000/kcp/blob/master/ikcp.c"
    author       = "@x0rc1sm"
    description  = "taking print and log reference from KCP, trying to find other implementations"
    category     = "info"
    malware_type = "N/A"
    mitre_att    = "N/A"
    actor_type   = "N/A"
    actor        = "N/A"
    report       = "N/A"
    hash         = ""
    hash         = ""
    hash         = ""

  strings:
    $kcp1  = "[RO] %ld bytes"      $kcp2  = "[RI] %d bytes"      $kcp3  = "recv sn=%lu"      $kcp4  = "input ack: sn=%lu rtt=%ld rto=%ld"      $kcp5  = "input psh: sn=%lu ts=%lu"      $kcp6  = "input probe"      $kcp7  = "input wins: %lu"      $kcp8  = "snd(buf=%d, queue=%d)\\n"      $kcp9  = "rcv(buf=%d, queue=%d)\\n"      $kcp10 = "rcv_nxt=%lu\\n"      $kcp11 = "rcvbuf"  
  condition:
    uint16(0) == 0x5a4d and 5 of them
}