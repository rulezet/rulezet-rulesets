rule TTP_XOR_QUAD_CurrentVersionRun_fbf0 {
  strings:
    $key_fbf0 = { a8 9f [2] 8c 91 [2] a7 bd [2] 89 9f [2] 9d 84 [2] 92 9e [2] 8c 83 [2] 8e 82 [2] 95 84 [2] 89 83 [2] 95 ac }

  condition:
    any of them
}