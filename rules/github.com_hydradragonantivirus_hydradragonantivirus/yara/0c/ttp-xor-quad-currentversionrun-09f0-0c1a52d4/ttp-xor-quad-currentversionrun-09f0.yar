rule TTP_XOR_QUAD_CurrentVersionRun_09f0 {
  strings:
    $key_09f0 = { 5a 9f [2] 7e 91 [2] 55 bd [2] 7b 9f [2] 6f 84 [2] 60 9e [2] 7e 83 [2] 7c 82 [2] 67 84 [2] 7b 83 [2] 67 ac }

  condition:
    any of them
}