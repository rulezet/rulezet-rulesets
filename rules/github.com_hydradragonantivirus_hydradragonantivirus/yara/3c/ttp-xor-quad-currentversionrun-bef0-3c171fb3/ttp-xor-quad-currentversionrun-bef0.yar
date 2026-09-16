rule TTP_XOR_QUAD_CurrentVersionRun_bef0 {
  strings:
    $key_bef0 = { ed 9f [2] c9 91 [2] e2 bd [2] cc 9f [2] d8 84 [2] d7 9e [2] c9 83 [2] cb 82 [2] d0 84 [2] cc 83 [2] d0 ac }

  condition:
    any of them
}