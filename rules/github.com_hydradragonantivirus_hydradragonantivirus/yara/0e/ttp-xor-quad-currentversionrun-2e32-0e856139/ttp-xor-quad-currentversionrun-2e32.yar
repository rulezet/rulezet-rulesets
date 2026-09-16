rule TTP_XOR_QUAD_CurrentVersionRun_2e32 {
  strings:
    $key_2e32 = { 7d 5d [2] 59 53 [2] 72 7f [2] 5c 5d [2] 48 46 [2] 47 5c [2] 59 41 [2] 5b 40 [2] 40 46 [2] 5c 41 [2] 40 6e }

  condition:
    any of them
}