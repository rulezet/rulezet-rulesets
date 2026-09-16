rule TTP_XOR_QUAD_CurrentVersionRun_3cf0 {
  strings:
    $key_3cf0 = { 6f 9f [2] 4b 91 [2] 60 bd [2] 4e 9f [2] 5a 84 [2] 55 9e [2] 4b 83 [2] 49 82 [2] 52 84 [2] 4e 83 [2] 52 ac }

  condition:
    any of them
}