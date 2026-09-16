rule TTP_XOR_QUAD_CurrentVersionRun_dcb5 {
  strings:
    $key_dcb5 = { 8f da [2] ab d4 [2] 80 f8 [2] ae da [2] ba c1 [2] b5 db [2] ab c6 [2] a9 c7 [2] b2 c1 [2] ae c6 [2] b2 e9 }

  condition:
    any of them
}