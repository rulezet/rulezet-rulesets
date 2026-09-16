rule TTP_XOR_QUAD_CurrentVersionRun_8ab9 {
  strings:
    $key_8ab9 = { d9 d6 [2] fd d8 [2] d6 f4 [2] f8 d6 [2] ec cd [2] e3 d7 [2] fd ca [2] ff cb [2] e4 cd [2] f8 ca [2] e4 e5 }

  condition:
    any of them
}