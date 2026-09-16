rule TTP_XOR_QUAD_CurrentVersionRun_1132 {
  strings:
    $key_1132 = { 42 5d [2] 66 53 [2] 4d 7f [2] 63 5d [2] 77 46 [2] 78 5c [2] 66 41 [2] 64 40 [2] 7f 46 [2] 63 41 [2] 7f 6e }

  condition:
    any of them
}