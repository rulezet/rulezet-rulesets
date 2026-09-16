rule DebuggerException__UnhandledFilter: AntiDebug DebuggerException {
  meta:
    author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules"
    weight    = 1

  strings:
    $ = "SetUnhandledExceptionFilter"

  condition:
    any of them
}