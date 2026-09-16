rule TTP_XOR_QUAD_CurrentVersionRun_26f0 {
  strings:
    $key_26f0 = { 75 9f [2] 51 91 [2] 7a bd [2] 54 9f [2] 40 84 [2] 4f 9e [2] 51 83 [2] 53 82 [2] 48 84 [2] 54 83 [2] 48 ac }

  condition:
    any of them
}