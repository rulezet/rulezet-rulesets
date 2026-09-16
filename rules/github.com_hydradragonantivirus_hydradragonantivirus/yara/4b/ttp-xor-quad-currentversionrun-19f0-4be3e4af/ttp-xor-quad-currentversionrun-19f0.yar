rule TTP_XOR_QUAD_CurrentVersionRun_19f0 {
  strings:
    $key_19f0 = { 4a 9f [2] 6e 91 [2] 45 bd [2] 6b 9f [2] 7f 84 [2] 70 9e [2] 6e 83 [2] 6c 82 [2] 77 84 [2] 6b 83 [2] 77 ac }

  condition:
    any of them
}