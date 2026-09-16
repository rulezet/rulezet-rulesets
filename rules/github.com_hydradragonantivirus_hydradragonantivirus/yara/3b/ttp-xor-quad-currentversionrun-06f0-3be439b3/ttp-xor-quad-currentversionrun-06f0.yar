rule TTP_XOR_QUAD_CurrentVersionRun_06f0 {
  strings:
    $key_06f0 = { 55 9f [2] 71 91 [2] 5a bd [2] 74 9f [2] 60 84 [2] 6f 9e [2] 71 83 [2] 73 82 [2] 68 84 [2] 74 83 [2] 68 ac }

  condition:
    any of them
}