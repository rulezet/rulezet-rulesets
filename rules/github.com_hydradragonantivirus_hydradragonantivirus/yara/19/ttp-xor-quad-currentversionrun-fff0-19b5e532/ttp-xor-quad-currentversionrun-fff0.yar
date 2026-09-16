rule TTP_XOR_QUAD_CurrentVersionRun_fff0 {
  strings:
    $key_fff0 = { ac 9f [2] 88 91 [2] a3 bd [2] 8d 9f [2] 99 84 [2] 96 9e [2] 88 83 [2] 8a 82 [2] 91 84 [2] 8d 83 [2] 91 ac }

  condition:
    any of them
}