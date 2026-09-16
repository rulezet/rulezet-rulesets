rule TTP_XOR_QUAD_CurrentVersionRun_3ef0 {
  strings:
    $key_3ef0 = { 6d 9f [2] 49 91 [2] 62 bd [2] 4c 9f [2] 58 84 [2] 57 9e [2] 49 83 [2] 4b 82 [2] 50 84 [2] 4c 83 [2] 50 ac }

  condition:
    any of them
}