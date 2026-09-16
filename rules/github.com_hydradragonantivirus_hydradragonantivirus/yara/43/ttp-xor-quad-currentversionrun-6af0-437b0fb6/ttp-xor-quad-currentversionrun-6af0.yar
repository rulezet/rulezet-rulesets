rule TTP_XOR_QUAD_CurrentVersionRun_6af0 {
  strings:
    $key_6af0 = { 39 9f [2] 1d 91 [2] 36 bd [2] 18 9f [2] 0c 84 [2] 03 9e [2] 1d 83 [2] 1f 82 [2] 04 84 [2] 18 83 [2] 04 ac }

  condition:
    any of them
}