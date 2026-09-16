rule TTP_XOR_QUAD_CurrentVersionRun_0932 {
  strings:
    $key_0932 = { 5a 5d [2] 7e 53 [2] 55 7f [2] 7b 5d [2] 6f 46 [2] 60 5c [2] 7e 41 [2] 7c 40 [2] 67 46 [2] 7b 41 [2] 67 6e }

  condition:
    any of them
}