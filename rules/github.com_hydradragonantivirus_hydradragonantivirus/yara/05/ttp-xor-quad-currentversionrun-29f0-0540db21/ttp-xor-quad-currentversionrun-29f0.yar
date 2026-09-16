rule TTP_XOR_QUAD_CurrentVersionRun_29f0 {
  strings:
    $key_29f0 = { 7a 9f [2] 5e 91 [2] 75 bd [2] 5b 9f [2] 4f 84 [2] 40 9e [2] 5e 83 [2] 5c 82 [2] 47 84 [2] 5b 83 [2] 47 ac }

  condition:
    any of them
}