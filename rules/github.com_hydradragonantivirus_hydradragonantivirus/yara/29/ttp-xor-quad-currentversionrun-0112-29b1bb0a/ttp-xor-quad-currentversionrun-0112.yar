rule TTP_XOR_QUAD_CurrentVersionRun_0112 {
  strings:
    $key_0112 = { 52 7d [2] 76 73 [2] 5d 5f [2] 73 7d [2] 67 66 [2] 68 7c [2] 76 61 [2] 74 60 [2] 6f 66 [2] 73 61 [2] 6f 4e }

  condition:
    any of them
}