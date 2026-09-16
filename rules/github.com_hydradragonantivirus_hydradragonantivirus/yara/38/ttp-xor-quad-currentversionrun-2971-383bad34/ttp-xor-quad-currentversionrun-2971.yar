rule TTP_XOR_QUAD_CurrentVersionRun_2971 {
  strings:
    $key_2971 = { 7a 1e [2] 5e 10 [2] 75 3c [2] 5b 1e [2] 4f 05 [2] 40 1f [2] 5e 02 [2] 5c 03 [2] 47 05 [2] 5b 02 [2] 47 2d }

  condition:
    any of them
}