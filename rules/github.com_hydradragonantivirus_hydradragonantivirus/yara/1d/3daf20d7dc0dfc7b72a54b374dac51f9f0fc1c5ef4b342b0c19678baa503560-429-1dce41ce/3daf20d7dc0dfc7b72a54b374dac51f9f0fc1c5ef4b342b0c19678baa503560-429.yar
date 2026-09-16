rule _3daf20d7dc0dfc7b72a54b374dac51f9f0fc1c5ef4b342b0c19678baa503560_429 {
  meta:
    description = "datamaliciousorder - from files 3daf20d7dc0dfc7b72a54b374dac51f9f0fc1c5ef4b342b0c19678baa503560f.js, 43f8f3eb47f80cf4e1b71484ae5b7d2f168eab3c975117749d9341b7de559076.js, c0eb3e8541a53faaabd8e32921a9fa6213a47f17547b60927738e2f1b7511a94.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3daf20d7dc0dfc7b72a54b374dac51f9f0fc1c5ef4b342b0c19678baa503560f"
    hash2       = "43f8f3eb47f80cf4e1b71484ae5b7d2f168eab3c975117749d9341b7de559076"
    hash3       = "c0eb3e8541a53faaabd8e32921a9fa6213a47f17547b60927738e2f1b7511a94"

  strings:
    $s1  = " * WSHModule: shell" fullword ascii
    $s2  = "(function(/*context, shell*/) {" fullword ascii
    $s3  = "  global.WSHModule._postCommand = function(command, options) {" fullword ascii
    $s4  = "    execute: function() {" fullword ascii
    $s5  = "      return eval(this._getShellStatement());" fullword ascii
    $s6  = "  return WSHModuleShell;" fullword ascii
    $s7  = "        delete context._getShellStatement;" fullword ascii
    $s8  = "      context._getShellStatement = function() {" fullword ascii
    $s9  = "if (typeof module === 'undefined' || !module.exports) {" fullword ascii
    $s10 = "        return _orginal_postCommand.apply(this, arguments);" fullword ascii
    $s11 = "    switch (command) {" fullword ascii
    $s12 = "      return this._closed = stdin.AtEndOfStream;" fullword ascii
    $s13 = "  return (function() {" fullword ascii
    $s14 = "}((function() { return this; }()) || this || {}, this, function() {" fullword ascii
    $s15 = "  var env = require('env');" fullword ascii
    $s16 = "}(this, function(global, scope, evalInContext) {" fullword ascii
    $s17 = "    command = command.toLowerCase().replace(/\\W+/g, '');" fullword ascii
    $s18 = "    readAll: function() {" fullword ascii
    $s19 = "    closed: function() {" fullword ascii
    $s20 = "      return stdin.ReadLine();" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (8 of them)
    ) or (all of them)
}