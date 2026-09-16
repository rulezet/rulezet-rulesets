rule TTP_XOR_QUAD_CurrentVersionRun_82b9 {
  strings:
    $key_82b9 = { d1 d6 [2] f5 d8 [2] de f4 [2] f0 d6 [2] e4 cd [2] eb d7 [2] f5 ca [2] f7 cb [2] ec cd [2] f0 ca [2] ec e5 }

  condition:
    any of them
}