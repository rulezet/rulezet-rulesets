rule TTP_XOR_QUAD_CurrentVersionRun_dcf0 {
  strings:
    $key_dcf0 = { 8f 9f [2] ab 91 [2] 80 bd [2] ae 9f [2] ba 84 [2] b5 9e [2] ab 83 [2] a9 82 [2] b2 84 [2] ae 83 [2] b2 ac }

  condition:
    any of them
}