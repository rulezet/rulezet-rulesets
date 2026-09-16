rule TTP_XOR_MULT_DOSStub_afcd {
  strings:
    $key_afcd = { fb a5 [2] 8f bd [2] c8 bf [2] 8f ae [2] c1 a2 [2] cd a8 [2] da a3 [2] c1 ed [2] fc }

  condition:
    any of them
}