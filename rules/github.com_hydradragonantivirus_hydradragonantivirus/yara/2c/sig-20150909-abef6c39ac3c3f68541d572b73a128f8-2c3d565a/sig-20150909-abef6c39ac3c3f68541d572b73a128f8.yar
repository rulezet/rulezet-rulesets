rule sig_20150909_abef6c39ac3c3f68541d572b73a128f8 {
  meta:
    description = "datamaliciousorder - file 20150909_abef6c39ac3c3f68541d572b73a128f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61f119d977fe6ebb1c84f2377c6c22ce23584241d0f1b79fddfcdae8ce704c4c"

  strings:
    $s1  = "ontroller.script.numScenes-1){if(l===0){e=true}}}else{if(this.lastSceneIndex+1===l){e=true}}if(e){if(gShowController.state===kSh" ascii
    $s2  = "ShowController.jumpToScene(a,false)},sceneIndexFromNavigationEvent:function(e){var c=e.slide;var f=gShowController.script.slideL" ascii
    $s3  = "ist;var b=-1;for(var a=0,d=f.length;a<d;a++){if(f[a]===c){b=a;break}}var h=gShowController.scriptManager.sceneIndexFromSlideInde" ascii
    $s4  = "leAtFinalState){gShowController.jumpToScene(this.lastSceneIndex,true)}}}else{var k=gShowController.scriptManager.slideIndexFromS" ascii
    $s5  = "var NarrationManager=Class.create({initialize:function(b){this.movieSegments=b.movieSegments;this.duration=b.duration;this.event" ascii
    $s6  = "].url;Event.observe(a,\"playing\",this.handleAudioDidStart.bind(this));Event.observe(a,\"ended\",this.handleAudioDidEnd.bind(thi" ascii
    $s7  = "astSceneIndex=l;this.currentNavigationEventIndex=this.currentNavigationEventIndex+1},handleCurrentSceneDidComplete:function(a){g" ascii
    $s8  = "c,\"ended\");Event.observe(c,\"ended\",this.handleAudioDidEnd.bind(this,a))}},navigate:function(a,h){var l=this.sceneIndexFromNa" ascii
    $s9  = "entNavigationEventIndex+1];if(n==null){return}var c=n.startTime-a.startTime;setTimeout(this.navigate.bind(this,n),c*1000);this.l" ascii
    $s10 = " a=this.eventTracks[c];if(a.type===\"navigation\"){this.navigationEvents=a.events}else{if(a.type===\"movie\"){this.movieEvents=a" ascii
    $s11 = "ength;a<c;a++){if(d[a]===b){e=a;break}}return e}});" fullword ascii
    $s12 = "x(b);var g=e.eventIndex+h;return g},slideIndexFromSlideId:function(b){var d=gShowController.slideList;var e=-1;for(var a=0,c=d.l" ascii
    $s13 = ");a.play()},handleAudioDidStart:function(){setTimeout(this.navigate(this.navigationEvents[0],true),100)},handleAudioDidEnd:funct" ascii
    $s14 = "owControllerState_IdleAtInitialState){gShowController.playCurrentScene()}else{if(gShowController.state===kShowControllerState_Id" ascii
    $s15 = "d++){m=j[d];f=m.events[a.slide];if(f){break}}if(m){gShowController.jumpToHyperlinkSlide(k,m)}else{gShowController.jumpToScene(l," ascii
    $s16 = "false)}}}else{if(a.animationPhase===\"none\"&&h==null){gShowController.jumpToScene(l,false)}}var n=this.navigationEvents[this.cu" ascii
    $s17 = "ion(b){var a=b+1;if(this.movieSegments[a]){var c=new Audio();c.src=\"../\"+this.movieSegments[a].url;c.play();Event.stopObservin" ascii
    $s18 = "nts}else{if(a.type===\"pause\"){this.pauseEvents=a.events}}}}},start:function(){var a=new Audio();a.src=\"../\"+this.movieSegmen" ascii
    $s19 = "var NarrationManager=Class.create({initialize:function(b){this.movieSegments=b.movieSegments;this.duration=b.duration;this.event" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}