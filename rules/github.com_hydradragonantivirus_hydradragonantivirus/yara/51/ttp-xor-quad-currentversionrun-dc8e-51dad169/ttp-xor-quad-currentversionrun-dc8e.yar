rule TTP_XOR_QUAD_CurrentVersionRun_dc8e {
  strings:
    $key_dc8e = { 8f e1 [2] ab ef [2] 80 c3 [2] ae e1 [2] ba fa [2] b5 e0 [2] ab fd [2] a9 fc [2] b2 fa [2] ae fd [2] b2 d2 }

  condition:
    any of them
}