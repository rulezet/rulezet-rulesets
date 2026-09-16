rule TTP_XOR_QUAD_CurrentVersionRun_0af0 {
  strings:
    $key_0af0 = { 59 9f [2] 7d 91 [2] 56 bd [2] 78 9f [2] 6c 84 [2] 63 9e [2] 7d 83 [2] 7f 82 [2] 64 84 [2] 78 83 [2] 64 ac }

  condition:
    any of them
}