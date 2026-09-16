rule TTP_XOR_QUAD_CurrentVersionRun_3df0 {
  strings:
    $key_3df0 = { 6e 9f [2] 4a 91 [2] 61 bd [2] 4f 9f [2] 5b 84 [2] 54 9e [2] 4a 83 [2] 48 82 [2] 53 84 [2] 4f 83 [2] 53 ac }

  condition:
    any of them
}