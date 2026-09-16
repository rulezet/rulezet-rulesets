rule TTP_XOR_QUAD_CurrentVersionRun_2932 {
  strings:
    $key_2932 = { 7a 5d [2] 5e 53 [2] 75 7f [2] 5b 5d [2] 4f 46 [2] 40 5c [2] 5e 41 [2] 5c 40 [2] 47 46 [2] 5b 41 [2] 47 6e }

  condition:
    any of them
}