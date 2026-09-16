rule TTP_XOR_QUAD_CurrentVersionRun_faf0 {
  strings:
    $key_faf0 = { a9 9f [2] 8d 91 [2] a6 bd [2] 88 9f [2] 9c 84 [2] 93 9e [2] 8d 83 [2] 8f 82 [2] 94 84 [2] 88 83 [2] 94 ac }

  condition:
    any of them
}