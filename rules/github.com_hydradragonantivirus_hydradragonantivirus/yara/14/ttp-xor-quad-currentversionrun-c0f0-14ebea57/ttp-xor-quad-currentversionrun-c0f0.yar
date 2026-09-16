rule TTP_XOR_QUAD_CurrentVersionRun_c0f0 {
  strings:
    $key_c0f0 = { 93 9f [2] b7 91 [2] 9c bd [2] b2 9f [2] a6 84 [2] a9 9e [2] b7 83 [2] b5 82 [2] ae 84 [2] b2 83 [2] ae ac }

  condition:
    any of them
}