rule DebuggerCheck__API: AntiDebug DebuggerCheck {
  meta:
    author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules"
    weight    = 1

  strings:
    $ = "IsDebuggerPresent"

  condition:
    any of them
}