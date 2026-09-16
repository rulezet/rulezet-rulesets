rule TTP_XOR_QUAD_CurrentVersionRun_3812 {
  strings:
    $key_3812 = { 6b 7d [2] 4f 73 [2] 64 5f [2] 4a 7d [2] 5e 66 [2] 51 7c [2] 4f 61 [2] 4d 60 [2] 56 66 [2] 4a 61 [2] 56 4e }

  condition:
    any of them
}