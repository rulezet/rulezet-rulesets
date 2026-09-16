rule sig_20150909_475ea7a46b81de644fbf245b8d508461 {
  meta:
    description = "datamaliciousorder - file 20150909_475ea7a46b81de644fbf245b8d508461.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6e4a4d8fdcbec5890ec4609cecd95d76ebdf66318130b47c1207e764e6437ce"

  strings:
    $x1  = "var Prototype={Version:\"1.7\",Browser:(function(){var b=navigator.userAgent;var a=Object.prototype.toString.call(window.opera)=" ascii
    $x2  = "(function(){var q=/((?:\\((?:\\([^()]+\\)|[^()]+)+\\)|\\[(?:\\[[^[\\]]*\\]|['\"][^'\"]*['\"]|[^[\\]'\"]+)+\\]|\\\\.|[^ >+~,(\\[" ascii
    $s3  = "anslations.tags){while(l.firstChild){l.removeChild(l.firstChild)}Element._getContentFromAnonymousElement(j,m.stripScripts()).eac" ascii
    $s4  = "(separator||\"&\").inject({},function(hash,pair){if((pair=pair.split(\"=\"))[0]){var key=decodeURIComponent(pair.shift()),value=" ascii
    $s5  = "n d(p){return new Hash(p).inject(this,function(q,r){q.set(r.key,r.value);return q})}function b(p,q){if(Object.isUndefined(q)){re" ascii
    $s6  = "\"==d[3]){break}g=g.substring(\"[\"==d[3]?d[1].length:d[0].length);d=e.exec(g)}return f+String.interpret(b)})}});Template.Patter" ascii
    $s7  = "I,H,A,t,s=true,x=p(u),G=E;while((q.exec(\"\"),D=q.exec(G))!==null){G=D[3];C.push(D[1]);if(D[2]){t=D[3];break}}if(C.length>1&&k.e" ascii
    $s8  = "var Prototype={Version:\"1.7\",Browser:(function(){var b=navigator.userAgent;var a=Object.prototype.toString.call(window.opera)=" ascii
    $s9  = "ent.Layout.COMPOSITE_PROPERTIES.include(x)){return}var y=this.get(x);if(y!=null){v[f(x)]=y+\"px\"}},this);return v},inspect:func" ascii
    $s10 = "ting=true;this.execute();this.currentlyExecuting=false}catch(a){this.currentlyExecuting=false;throw a}}}});Object.extend(String," ascii
    $s11 = "ght:this.getHeight()}},getScrollOffsets:function(){return Element._returnOffset(window.pageXOffset||document.documentElement.scr" ascii
    $s12 = "Child)}var h=Element._getContentFromAnonymousElement(j,m.stripScripts(),true);h.each(function(i){l.appendChild(i)})}else{l.inner" ascii
    $s13 = "ent.createElement(\"form\"),a=false;if(c.__proto__&&(c.__proto__!==b.__proto__)){a=true}c=b=null;return a})()},ScriptFragment:\"" ascii
    $s14 = "Value=this.getValue()},execute:function(){var a=this.getValue();if(Object.isString(this.lastValue)&&Object.isString(a)?this.last" ascii
    $s15 = "){this.respondToReadyState(this.transport.readyState)}},setRequestHeaders:function(){var e={\"X-Requested-With\":\"XMLHttpReques" ascii
    $s16 = "eft\"),top:u.getStyle(\"top\"),width:u.getStyle(\"width\"),height:u.getStyle(\"height\")});u.setStyle({position:\"absolute\",top" ascii
    $s17 = "ort.onreadystatechange=this.onStateChange.bind(this);this.setRequestHeaders();this.body=this.method==\"post\"?(this.options.post" ascii
    $s18 = "{c=\"\";b=function(i,j,k){return i+(i?\"&\":\"\")+encodeURIComponent(j)+\"=\"+encodeURIComponent(k)}}return h.inject(c,function(" ascii
    $s19 = "bstract.TimedObserver=Class.create(PeriodicalExecuter,{initialize:function($super,a,b,c){$super(c,b);this.element=$(a);this.last" ascii
    $s20 = "var x=Object.keys(C.Methods).inject({},function(E,F){E[F]=C.Methods[F].methodize();return E});if(window.attachEvent){function i(" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}