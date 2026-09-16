rule TTP_XOR_QUAD_CurrentVersionRun_6bf0 {
  strings:
    $key_6bf0 = { 38 9f [2] 1c 91 [2] 37 bd [2] 19 9f [2] 0d 84 [2] 02 9e [2] 1c 83 [2] 1e 82 [2] 05 84 [2] 19 83 [2] 05 ac }

  condition:
    any of them
}