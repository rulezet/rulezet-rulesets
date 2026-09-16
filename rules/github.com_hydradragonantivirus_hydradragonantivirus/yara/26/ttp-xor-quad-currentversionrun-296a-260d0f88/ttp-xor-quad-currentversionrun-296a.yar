rule TTP_XOR_QUAD_CurrentVersionRun_296a {
  strings:
    $key_296a = { 7a 05 [2] 5e 0b [2] 75 27 [2] 5b 05 [2] 4f 1e [2] 40 04 [2] 5e 19 [2] 5c 18 [2] 47 1e [2] 5b 19 [2] 47 36 }

  condition:
    any of them
}