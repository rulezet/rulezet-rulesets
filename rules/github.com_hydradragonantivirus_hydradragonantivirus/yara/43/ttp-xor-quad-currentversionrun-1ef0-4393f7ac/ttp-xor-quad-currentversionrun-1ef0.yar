rule TTP_XOR_QUAD_CurrentVersionRun_1ef0 {
  strings:
    $key_1ef0 = { 4d 9f [2] 69 91 [2] 42 bd [2] 6c 9f [2] 78 84 [2] 77 9e [2] 69 83 [2] 6b 82 [2] 70 84 [2] 6c 83 [2] 70 ac }

  condition:
    any of them
}