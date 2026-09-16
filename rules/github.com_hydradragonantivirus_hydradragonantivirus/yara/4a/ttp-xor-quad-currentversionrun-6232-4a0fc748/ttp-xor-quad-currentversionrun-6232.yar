rule TTP_XOR_QUAD_CurrentVersionRun_6232 {
  strings:
    $key_6232 = { 31 5d [2] 15 53 [2] 3e 7f [2] 10 5d [2] 04 46 [2] 0b 5c [2] 15 41 [2] 17 40 [2] 0c 46 [2] 10 41 [2] 0c 6e }

  condition:
    any of them
}