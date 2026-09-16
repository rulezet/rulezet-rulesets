rule TTP_XOR_QUAD_CurrentVersionRun_edf0 {
  strings:
    $key_edf0 = { be 9f [2] 9a 91 [2] b1 bd [2] 9f 9f [2] 8b 84 [2] 84 9e [2] 9a 83 [2] 98 82 [2] 83 84 [2] 9f 83 [2] 83 ac }

  condition:
    any of them
}