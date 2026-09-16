rule TTP_XOR_QUAD_CurrentVersionRun_db8e {
  strings:
    $key_db8e = { 88 e1 [2] ac ef [2] 87 c3 [2] a9 e1 [2] bd fa [2] b2 e0 [2] ac fd [2] ae fc [2] b5 fa [2] a9 fd [2] b5 d2 }

  condition:
    any of them
}