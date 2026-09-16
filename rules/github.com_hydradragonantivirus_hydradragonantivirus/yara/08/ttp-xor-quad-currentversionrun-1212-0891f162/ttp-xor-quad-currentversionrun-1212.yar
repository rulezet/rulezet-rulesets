rule TTP_XOR_QUAD_CurrentVersionRun_1212 {
  strings:
    $key_1212 = { 41 7d [2] 65 73 [2] 4e 5f [2] 60 7d [2] 74 66 [2] 7b 7c [2] 65 61 [2] 67 60 [2] 7c 66 [2] 60 61 [2] 7c 4e }

  condition:
    any of them
}