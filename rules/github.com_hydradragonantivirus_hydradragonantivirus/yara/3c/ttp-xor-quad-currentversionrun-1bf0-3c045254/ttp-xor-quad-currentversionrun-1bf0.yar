rule TTP_XOR_QUAD_CurrentVersionRun_1bf0 {
  strings:
    $key_1bf0 = { 48 9f [2] 6c 91 [2] 47 bd [2] 69 9f [2] 7d 84 [2] 72 9e [2] 6c 83 [2] 6e 82 [2] 75 84 [2] 69 83 [2] 75 ac }

  condition:
    any of them
}