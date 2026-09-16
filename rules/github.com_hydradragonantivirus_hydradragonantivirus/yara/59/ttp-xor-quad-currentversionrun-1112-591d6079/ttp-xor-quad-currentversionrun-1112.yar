rule TTP_XOR_QUAD_CurrentVersionRun_1112 {
  strings:
    $key_1112 = { 42 7d [2] 66 73 [2] 4d 5f [2] 63 7d [2] 77 66 [2] 78 7c [2] 66 61 [2] 64 60 [2] 7f 66 [2] 63 61 [2] 7f 4e }

  condition:
    any of them
}