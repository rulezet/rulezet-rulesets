rule TTP_XOR_QUAD_CurrentVersionRun_0ef0 {
  strings:
    $key_0ef0 = { 5d 9f [2] 79 91 [2] 52 bd [2] 7c 9f [2] 68 84 [2] 67 9e [2] 79 83 [2] 7b 82 [2] 60 84 [2] 7c 83 [2] 60 ac }

  condition:
    any of them
}