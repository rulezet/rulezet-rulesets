rule TTP_XOR_QUAD_CurrentVersionRun_3c32 {
  strings:
    $key_3c32 = { 6f 5d [2] 4b 53 [2] 60 7f [2] 4e 5d [2] 5a 46 [2] 55 5c [2] 4b 41 [2] 49 40 [2] 52 46 [2] 4e 41 [2] 52 6e }

  condition:
    any of them
}