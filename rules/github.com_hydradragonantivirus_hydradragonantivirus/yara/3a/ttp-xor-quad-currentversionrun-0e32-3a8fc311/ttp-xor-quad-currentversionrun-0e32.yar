rule TTP_XOR_QUAD_CurrentVersionRun_0e32 {
  strings:
    $key_0e32 = { 5d 5d [2] 79 53 [2] 52 7f [2] 7c 5d [2] 68 46 [2] 67 5c [2] 79 41 [2] 7b 40 [2] 60 46 [2] 7c 41 [2] 60 6e }

  condition:
    any of them
}