rule TTP_XOR_QUAD_CurrentVersionRun_19fc {
  strings:
    $key_19fc = { 4a 93 [2] 6e 9d [2] 45 b1 [2] 6b 93 [2] 7f 88 [2] 70 92 [2] 6e 8f [2] 6c 8e [2] 77 88 [2] 6b 8f [2] 77 a0 }

  condition:
    any of them
}