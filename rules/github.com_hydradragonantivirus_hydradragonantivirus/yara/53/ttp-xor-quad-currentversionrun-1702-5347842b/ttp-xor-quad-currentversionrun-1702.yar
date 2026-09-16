rule TTP_XOR_QUAD_CurrentVersionRun_1702 {
  strings:
    $key_1702 = { 44 6d [2] 60 63 [2] 4b 4f [2] 65 6d [2] 71 76 [2] 7e 6c [2] 60 71 [2] 62 70 [2] 79 76 [2] 65 71 [2] 79 5e }

  condition:
    any of them
}