rule TTP_XOR_QUAD_CurrentVersionRun_2951 {
  strings:
    $key_2951 = { 7a 3e [2] 5e 30 [2] 75 1c [2] 5b 3e [2] 4f 25 [2] 40 3f [2] 5e 22 [2] 5c 23 [2] 47 25 [2] 5b 22 [2] 47 0d }

  condition:
    any of them
}