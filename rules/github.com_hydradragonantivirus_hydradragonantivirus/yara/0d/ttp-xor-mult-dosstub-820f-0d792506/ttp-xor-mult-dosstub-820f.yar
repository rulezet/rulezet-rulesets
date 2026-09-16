rule TTP_XOR_MULT_DOSStub_820f {
  strings:
    $key_820f = { d6 67 [2] a2 7f [2] e5 7d [2] a2 6c [2] ec 60 [2] e0 6a [2] f7 61 [2] ec 2f [2] d1 }

  condition:
    any of them
}